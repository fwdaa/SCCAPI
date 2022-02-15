#include "stdafx.h"
#include "Store.h"

Aladdin::CAPI::Container^ Aladdin::CAPI::STB::Avest::CSP::SCardStore::CreateContainer(
	ContainerInfo^ info, Authentication^ authentication)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::SCardStore::CreateContainer); 
	
	// вызвать базовую функцию
	CAPI::ProviderStore::CreateContainer(info, authentication); 

	// определить описатель провайдера
	CAPI::CSP::ProviderHandle hProvider = ((CAPI::CSP::Provider^)Provider)->Handle; 

	// создать контейнер с использованием интерфейса
	CAPI::CSP::ContainerHandle hContainer = hProvider.AcquireContainer(info->UniqueName, CRYPT_NEWKEYSET); 

	// вернуть объект контейнера
	return gcnew CAPI::CSP::Container(info, hContainer, 0, authentication);		
}

void Aladdin::CAPI::STB::Avest::CSP::SCardStore::DeleteContainer(
	ContainerInfo^ info, Authentication^ authentication)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::SCardStore::DeleteContainer); 

	// определить описатель провайдера
	CAPI::CSP::ProviderHandle hProvider = ((CAPI::CSP::Provider^)Provider)->Handle; 

	// удалить контейнер с использованием интерфейса
	hProvider.DeleteContainer(info->UniqueName, 0); 

	// вызвать базовую функцию
	CAPI::CSP::ProviderStore::DeleteContainer(info, authentication); 
}
