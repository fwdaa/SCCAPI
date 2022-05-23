#include "stdafx.h"
#include "SCardStore.h"
#include "SCardContainer.h"
#include "PasswordService.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "SCardStore.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Хранилище контейнеров на смарт-карте
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::CryptoPro::SCardStore::SCardStore(SecurityStore^ store, String^ name) 

	// сохранить переданные параметры
	: ProviderStore(store, name, CryptoPro::SCardContainer::typeid, 0), applet(nullptr)
{$
	// определить имя считывателя
	String^ nativeName = String::Format("\\\\.\\{0}\\", Name->ToString());
	try { 
		// указать режим открытия
		DWORD openMode = Mode | CRYPT_SILENT; destroy = FALSE;

		// открыть описатель хранилища
		handle.Attach(Provider->Handle->AcquireStore(nativeName, openMode));
	}
	// при возникновении ошибки
	catch (Win32Exception^ e)
	{
		// проверить код ошибки
		if (e->NativeErrorCode != NTE_BAD_KEYSET && e->NativeErrorCode != NTE_KEYSET_NOT_DEF) throw;

		// указать режим открытия
		DWORD openMode = Mode | CRYPT_NEWKEYSET | CRYPT_SILENT; destroy = TRUE;

		// открыть описатель хранилища
		handle.Attach(Provider->Handle->AcquireStore(nativeName, openMode));
	}
/*	try { 
		// указать провайдер апплетов
		Using<IProvider^> provider(gcnew SCard::APDU::AppletProvider()); 

		// открыть смарт-карту как хранилище апплетов
		Using<SecurityStore^> store(provider->OpenStore(CAPI::Scope::System, Name->ToString())); 

		// открыть апплет Laser
		applet = store->OpenObject("Laser", FileAccess::Read); 
	}
	// обработать возможную ошибку
	catch (Exception^) {}
*/
} 

Aladdin::CAPI::CSP::CryptoPro::SCardStore::~SCardStore() 
{$
	// освободить выделенные ресурсы
	if (applet != nullptr) delete applet; if (destroy && handle.Get() != nullptr) 
	{
		// удалить контейнер
		try { handle.Get()->SetParam(PP_DELETE_KEYSET, IntPtr::Zero, 0); } catch (Exception^) {}
	}
} 

array<Type^>^ Aladdin::CAPI::CSP::CryptoPro::SCardStore::GetAuthenticationTypes(String^ user)
{$
	// проверить наличие апплета
	if (applet == nullptr) return gcnew array<Type^> { Auth::PasswordCredentials::typeid };
	try {
		// создать список допустимых аутентификаций
		List<Type^>^ authenticationTypes = gcnew List<Type^>(); 

		// указать наличие парольной аутентификации
		authenticationTypes->Add(Auth::PasswordCredentials::typeid); 

		// перечислить типы аутентификации апплета
		for each (Type^ authenticationType in applet->GetAuthenticationTypes(user))
		{
			// при отсутствии аутентификации в списке
			if (!authenticationTypes->Contains(authenticationType))
			{
				// добавить тип аутентификации в список
				authenticationTypes->Add(authenticationType); 
			}
		}
		// вернуть допустимые аутентификации
		return authenticationTypes->ToArray(); 
	}
    // вызвать базовую функцию
    catch (Exception^) { return gcnew array<Type^> { Auth::PasswordCredentials::typeid }; }
}

Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::CSP::CryptoPro::SCardStore::GetAuthenticationService(
	String^ user, Type^ authenticationType) 
{$
	// проверить тип аутентификации
	if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType)) 
	{
		// вернуть протокол аутентификации
		return gcnew PasswordService(this, Handle, false); 
	}
	// проверить наличие апплета
	if (applet == nullptr) return nullptr;

	// проверить тип аутентификации
	if (Auth::BiometricCredentials::typeid->IsAssignableFrom(authenticationType))
	try {
		// получить сервис биометрической аутентификации
		return applet->GetAuthenticationService(user, authenticationType); 
	}
	// обработать возможную ошибку
	catch (Exception^) {} return nullptr;
}

array<Aladdin::CAPI::Credentials^>^ Aladdin::CAPI::CSP::CryptoPro::SCardStore::Authenticate()
{$ 
	// вызвать базовую функцию
	array<Credentials^>^ results = CAPI::CSP::ProviderStore::Authenticate(); 

	// проверить поддержку апплета
	if (applet == nullptr) return results; String^ password = nullptr; 
	
	// тикет биометрической аутентификации
	SCard::APDU::Laser::LibBiometricTicket^ ticket = nullptr; 

	// для всех выполненных аутентификаций
	for each (Credentials^ credentials in results)
	{
		// получить тип аутентификации
		Type^ authenticationType = credentials->Types[0]; 

		// для биометрической аутентификации
		if (Auth::BiometricCredentials::typeid->IsAssignableFrom(authenticationType))
		{
			// выполнить преобразование типа
			Bio::MatchTemplate^ matchTemplate = ((Auth::BiometricCredentials^)credentials)->MatchTemplate; 

			// извлечь тикет биометрической аутентификации
			ticket = (SCard::APDU::Laser::LibBiometricTicket^)matchTemplate; 
		}
		// для парольной аутентификации
		else if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType))
		{
			// извлечь предоставленный пароль
			password = ((Auth::PasswordCredentials^)credentials)->Password; 
		}
	}
	// проверить наличие биометрической аутентификации
	if (ticket == nullptr) return results; String^ encoded = ticket->GetEncoded(password); 

	// указать парольную аутентификацию провайдера
	Auth::PasswordCredentials^ authentication = gcnew Auth::PasswordCredentials("USER", encoded); 

	// выполнить парольную аутентификацию провайдера
	authentication->Authenticate(this); return results; 
}

String^ Aladdin::CAPI::CSP::CryptoPro::SCardStore::GetUniqueID()
{$
    // получить подсистему смарт-карт
    PCSC::Windows::Provider^ provider = PCSC::Windows::Provider::Instance; 

	// указать область видимости
	PCSC::ReaderScope readerScope = (Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// получить уникальный идентификатор смарт-карты
	return provider->GetCardUniqueID(readerScope, Name->ToString()); 
}

array<String^>^ Aladdin::CAPI::CSP::CryptoPro::SCardStore::EnumerateObjects()
{$
	// указать имя считывателя
	String^ reader = String::Format("\\\\.\\{0}\\", Name);

	// перечислить контейнеры
	array<String^>^ names = Handle->EnumerateContainers(CRYPT_FQCN); 

	// выделить память для имен контейнеров
	List<String^>^ containers = gcnew List<String^>(); 

	// для всех контейнеров
	for each (String^ name in names) 
	{ 
		// проверить считыватель контейнера
		if (!name->StartsWith(reader)) continue; 

		// добавить имя в список
		containers->Add(name->Substring(reader->Length));
	}
	// вернуть имена контейнеров 
	return containers->ToArray(); 
}

Aladdin::CAPI::SecurityObject^ 
Aladdin::CAPI::CSP::CryptoPro::SCardStore::CreateObject(
	IRand^ rand, Object^ name, Object^ authenticationData, ...array<Object^>^ parameters)
{$
	// создать объект контейнера
	Using<Container^> container((Container^)
		CAPI::CSP::ProviderStore::CreateObject(rand, name, authenticationData, parameters)
	); 
	// создать пустой контейнер
	container.Get()->Synchronize(); return container.Detach(); 
}

void Aladdin::CAPI::CSP::CryptoPro::SCardStore::DeleteObject(
	Object^ name, array<CAPI::Authentication^>^ authentications)
{$
	try {
		// открыть контейнер
		Using<Container^> container((Container^)OpenObject(name, FileAccess::ReadWrite)); 

		// удалить контейнер
		container.Get()->Authentications = authentications; container.Get()->Delete(); 
	}
	// обработать возможное исключение
	catch (NotFoundException^) {}

	// проверить код ошибки
	catch (Win32Exception^ ex) { if (ex->NativeErrorCode != NTE_BAD_KEYSET) throw; }

	// вызвать базовую функцию
	ContainerStore::DeleteObject(name, authentications); 
}
