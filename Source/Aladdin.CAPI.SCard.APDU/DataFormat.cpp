#include "StdAfx.h"
#include "DataApplet.h"
#include "NativeAPI.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "DataFormat.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Сервис форматирования
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::DataStore::Applet::Format(
    String^ userPIN, SCard::FormatParameters^ parameters) 
{$
	// преобразовать тип параметров
	FormatParameters^ params = dynamic_cast<FormatParameters^>(parameters);

	// проверить корректность типа параметров
	if (params == nullptr) throw gcnew ArgumentException();  

    // загрузить модуль PKCS11
	PKCS11::Module^ module = PKCS11::Module::Create(gcnew NativeAPI()); 

    // перечислить считыватели со вставленной смарт-картой
    array<UInt64>^ slotsIds = module->GetSlotList(true);

    // для всех считывателей
	for (int i = 0; i < slotsIds->Length; i++)
	{
        // получить информацию считывателя
	    PKCS11::SlotInfo^ info = module->GetSlotInfo(slotsIds[i]);

        // проверить совпадение имени
		if (info->SlotDescription != Card->Reader->Name) continue; 

        // закрыть все сеансы смарт-карты
	    module->CloseAllSessions(slotsIds[i]);  

        // выполнить форматирование 
        module->InitToken(slotsIds[i], userPIN, String::Empty); return; 
    }
	// при ошибке выбросить исключение
	throw gcnew NotFoundException(); 
}
