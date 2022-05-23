#include "stdafx.h"
#include "RegistryStore.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RegistryStore.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Хранилище контейнеров в реестре
///////////////////////////////////////////////////////////////////////////
array<String^>^ Aladdin::CAPI::CSP::CryptoPro::RegistryStore::EnumerateObjects()
{$
	// указать имя считывателя
	String^ reader = String::Format("\\\\.\\{0}\\", "REGISTRY");

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
Aladdin::CAPI::CSP::CryptoPro::RegistryStore::CreateObject(
	IRand^ rand, Object^ name, Object^ authenticationData, ...array<Object^>^ parameters)
{$
	// создать контейнер
	Using<Container^> container((Container^)
		CAPI::CSP::ProviderStore::CreateObject(rand, name, authenticationData, parameters)
	); 
	// создать пустой контейнер
	if (authenticationData == nullptr) container.Get()->Synchronize();
	else {
		// получить сервис аутентификации
		Auth::PasswordService^ service = (Auth::PasswordService^)
			container.Get()->GetAuthenticationService(
				"USER", Auth::PasswordCredentials::typeid
		); 
		// указать начальный пароль
		service->Change((String^)authenticationData); 

		// сохранить аутентификацию
		Authentication = gcnew Auth::PasswordCredentials(
			"USER", (String^)authenticationData
		); 
	}
	// вернуть объект контейнера
	return container.Detach(); 
}

void Aladdin::CAPI::CSP::CryptoPro::RegistryStore::DeleteObject(
	Object^ name, array<CAPI::Authentication^>^ authentications)
{$
	try { 
		// открыть объект контейнера
		Using<Container^> container((Container^)OpenObject(name, FileAccess::ReadWrite)); 
		 
		// указать способ аутентификации и удалить контейнер
		container.Get()->Authentications = authentications; container.Get()->Delete(); 
	}
	// обработать возможное исключение
	catch (NotFoundException^) {}

	// проверить код ошибки
	catch (Win32Exception^ ex) { if (ex->NativeErrorCode != NTE_BAD_KEYSET) throw; }

	// вызвать базовую функцию
	ContainerStore::DeleteObject(name, authentications); 
}

