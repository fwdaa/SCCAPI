#include "stdafx.h"
#include "Provider.h"
#include "ProApplet.h"
#include "GostApplet.h"
#include "DataApplet.h"
#include "LaserApplet.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider.tmh"
#endif 

using namespace Aladdin::PCSC; 

///////////////////////////////////////////////////////////////////////////
// Провайдер апплетов
///////////////////////////////////////////////////////////////////////////
array<String^>^ Aladdin::CAPI::SCard::APDU::ProviderImpl::EnumerateApplets(SCard::Card^ store)
{$
	// преобразовать тип считывателя
	PCSC::Reader^ reader = (PCSC::Reader^)store->PCSCCard->Reader; 

	// указать допустимые протоколы
	Protocol protocols = Protocol::T0 | Protocol::T1; 

    // открыть сеанс
    PCSC::ReaderSession^ session = reader->CreateSession(OpenMode::Shared, protocols);
	try {
		// получить ATR смарт-карты
		array<BYTE>^ atr = session->ATR->Encoded; 

		// перечислить апплеты EToken JavaCard и JaCarta
		if (jcFamily->Contains(atr)) return jcFamily->EnumerateApplets(session, atr); 

		// перечислить апплеты EToken
		if (etFamily->Contains(atr)) return etFamily->EnumerateApplets(session, atr); 

		// апплетов не обнаружено
		return gcnew array<String^>(0); 
	}
	// освободить выделенные ресурсы
	finally { delete session; }
}

Aladdin::CAPI::SCard::Applet^ 
Aladdin::CAPI::SCard::APDU::ProviderImpl::OpenApplet(SCard::Card^ store, String^ name)
{$
	// преобразовать тип считывателя
	PCSC::Reader^ reader = (PCSC::Reader^)store->PCSCCard->Reader; 

	// указать допустимые протоколы
	Protocol protocols = Protocol::T0 | Protocol::T1; 

    // открыть сеанс
    PCSC::ReaderSession^ session = reader->CreateSession(OpenMode::Shared, protocols);
	try {
		// получить ATR смарт-карты
		array<BYTE>^ atr = session->ATR->Encoded; 

		// для семейства EToken JavaCard и JaCarta
		if (jcFamily->Contains(atr))
		{
			// открыть апплет требуемого типа
			if (name == "Laser"      ) return Laser      ::Applet::Create(store, session, atr); 
			if (name == "DataStore"  ) return DataStore  ::Applet::Create(store, session, atr); 
			if (name == "Cryptotoken") return Cryptotoken::Applet::Create(store, session, atr); 
			if (name == "ProJava"    ) return Pro    ::AppletJava::Create(store, session, atr); 
		}
		// для семейства EToken
		if (etFamily->Contains(atr))
		{
			// открыть апплет требуемого типа
			if (name == "Pro") return Pro::Applet::Create(store, session, atr); 
		}
		// при ошибке выбросить исключение
		throw gcnew NotSupportedException(); 
	}
	// обработать возможную ошибку
	catch (System::Exception^) { delete session; throw; }
}
