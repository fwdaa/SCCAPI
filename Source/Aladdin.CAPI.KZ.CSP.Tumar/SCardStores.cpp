#include "stdafx.h"
#include "SCardStores.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "SCardStores.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Смарт-карты как устройство хранения
///////////////////////////////////////////////////////////////////////////
String^ Aladdin::CAPI::KZ::CSP::Tumar::SCardStores::GetNativeContainerName(String^ name)
{$
	// закодировать имя считывателя
	String^ reader = name->Replace(" ", "%20"); 

	// сформировать полное имя контейнера
	return String::Format("kztoken://{0}@/{1}?ext=tok", "NONAME", reader); 
}

array<String^>^ Aladdin::CAPI::KZ::CSP::Tumar::SCardStores::EnumerateObjects()
{$
	// создать список имен считывателей
	List<String^>^ names = gcnew List<String^>(); DWORD mode = CRYPT_SILENT;

    // получить подсистему смарт-карт
    PCSC::Provider^ provider = PCSC::Windows::Provider::Instance; 

	// указать область видимости
	PCSC::ReaderScope readerScope = (Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// перечислить считыватели
	array<PCSC::Reader^>^ readers = provider->EnumerateReaders(readerScope); 

	// для каждой смарт-карты
	for (int i = 0; i < readers->Length; i++) 
	try {
		// проверить наличие смарт-карты 
		if (readers[i]->GetState() != PCSC::ReaderState::Card) continue; 
		 			
		// сформировать полное имя контейнера
		String^ nativeName = GetNativeContainerName(readers[i]->Name); 

		// попытаться открыть смарт-карту
		Using<CAPI::CSP::ContainerHandle^> handle(
			Provider->Handle->AcquireContainer(nativeName, mode)
		); 
		// добавить имя считывателя
		names->Add(readers[i]->Name);
	}
	// вернуть список имен
	catch (Exception^) {} return names->ToArray(); 
}

