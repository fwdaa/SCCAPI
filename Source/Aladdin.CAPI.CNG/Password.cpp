#include "stdafx.h"
#include "Password.h"
#include "Provider.h"

///////////////////////////////////////////////////////////////////////////
// Кэш паролей по отдельным контейнерам
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::ContainerPasswordCache::SetPassword(String^ container, String^ password)
{
	ATRACE_SCOPE(Aladdin::CAPI::CNG::ContainerPasswordCache::SetPassword); 

	// определить имя контейнера
	String^ name = GetContainerName(container); 

	// при отсутствии пароле для контейнера
	if (!passwords->ContainsKey(name))  
	{
		// создать список паролей для контейнера
		List<String^>^ list = gcnew List<String^>(); 

		// добавить пароль в список
		list->Add(password); passwords->Add(name, list);  
	}
	// проверить отсутствие заданного пароля
	else if (passwords[name]->Contains(password)) {} 
	
	// добавить пароль контейнера 
	else passwords[name]->Insert(0, password); 
}

array<String^>^ Aladdin::CAPI::CNG::ContainerPasswordCache::GetPasswords(String^ container)
{
	ATRACE_SCOPE(Aladdin::CAPI::CNG::ContainerPasswordCache::GetPasswords); 

	// определить имя контейнера
	String^ name = GetContainerName(container); 

	// проверить наличие паролей для контейнера
	if (passwords->ContainsKey(name)) return passwords[name]->ToArray(); 

	// вернуть пустой список паролей
	return gcnew array<String^>(0); 
}

String^ Aladdin::CAPI::CNG::ContainerPasswordCache::GetContainerName(String^ container)
{
	ATRACE_SCOPE(Aladdin::CAPI::CNG::ContainerPasswordCache::GetContainerName); 

	// проверить наличие префикса
	if (container->Length < 5 || container->Substring(0, 4) != L"\\\\.\\") return container; 

	// найти позицию завершения имени считывателя
	int position = container->IndexOf(L'\\', 4); if (position < 0) return container;

	// извлечь имя контейнера
	return container->Substring(position + 1); 
}

///////////////////////////////////////////////////////////////////////////
// Создание контейнера
///////////////////////////////////////////////////////////////////////////
Object^ Aladdin::CAPI::CNG::CreateContainerAction::PasswordInvoke(String^ password) 
{ 
	ATRACE_SCOPE(Aladdin::CAPI::CNG::CreateContainerAction::PasswordInvoke); 

	// создать контейнер
	Object^ obj = provider->CreateContainer(container, password);

	// получить кэш паролей
	IPasswordCache^ cache = provider->PasswordCache; 

	// сохранить пароль в кэш
	cache->SetPassword(container, password); return obj;
} 

Object^ Aladdin::CAPI::CNG::CreateContainerAction::Invoke()
{
	ATRACE_SCOPE(Aladdin::CAPI::CNG::CreateContainerAction::Invoke); 

	// создать контейнер
	return gcnew CSP::Container(provider, container, 
		container, flags | CRYPT_NEWKEYSET, callback
	); 
}

///////////////////////////////////////////////////////////////////////////
// Удаление контейнера
///////////////////////////////////////////////////////////////////////////
Object^ Aladdin::CAPI::CNG::DeleteContainerAction::PasswordInvoke(String^ password) 
{ 
	ATRACE_SCOPE(Aladdin::CAPI::CNG::DeleteContainerAction::PasswordInvoke); 

	// удалить контейнер
	provider->DeleteContainer(container, password); return nullptr; 
} 

Object^ Aladdin::CAPI::CNG::DeleteContainerAction::Invoke()
{
	ATRACE_SCOPE(Aladdin::CAPI::CNG::DeleteContainerAction::Invoke); 

	// удалить контейнер
	provider->Handle->DeleteContainer(container, CRYPT_SILENT); return nullptr; 
}

///////////////////////////////////////////////////////////////////////////
// Действие с контейнером, производимое после аутентификации
///////////////////////////////////////////////////////////////////////////
Object^ Aladdin::CAPI::CNG::ContainerPasswordAction::PasswordInvoke(String^ password) 
{ 
	ATRACE_SCOPE(Aladdin::CAPI::CNG::ContainerPasswordAction::PasswordInvoke); 

	// преобразовать тип провайдера
	PasswordProvider^ provider = (PasswordProvider^)container->Provider; 

	// выполнить функцию после установки пароля
	container->Password = password; Object^ obj = Invoke();

	// получить кэш паролей
	IPasswordCache^ cache = provider->PasswordCache; 

	// сохранить пароль в кэш
	cache->SetPassword(container->Name, password); return obj;
} 

