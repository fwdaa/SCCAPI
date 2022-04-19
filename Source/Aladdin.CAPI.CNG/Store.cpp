#include "stdafx.h"
#include "Store.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Store.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Сервис парольной аутентификации
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::PasswordService::SetPassword(String^ password) 
{$
	// при аутентификации контейнера
	NKeyHandle^ handle = this->handle; if (handle == nullptr)
	{
		// получить описатель пары ключей
		handle = ((Container^)Target)->Handle;
	}
	// установить пароль на ключ
	handle->SetString(NCRYPT_PIN_PROPERTY, password, 0); 
}

///////////////////////////////////////////////////////////////////////////
// Устройства хранения 
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CNG::ProviderStore::IsAuthenticationRequired(Exception^ e)
{$
	// проверить тип исключения
	if (dynamic_cast<Win32Exception^>(e) == nullptr) return false; 

	// определить код ошибки
	DWORD code = (((Win32Exception^)e)->NativeErrorCode); 

	// проверить код ошибки
	if (code == NTE_SILENT_CONTEXT || code == NTE_FAIL) return true; 

	// проверить код ошибки
	return code == SCARD_W_SECURITY_VIOLATION || 
		   code == SCARD_E_INVALID_CHV || code == SCARD_W_WRONG_CHV; 
}

array<String^>^ Aladdin::CAPI::CNG::ProviderStore::EnumerateObjects()
{$
	// проверить область видимости
	if (Scope == CAPI::Scope::User) return gcnew array<String^>(0); 

	// перечислить ключи
	return Provider->Handle->EnumerateKeys(nullptr, NCRYPT_SILENT_FLAG); 
}

Aladdin::CAPI::SecurityObject^ Aladdin::CAPI::CNG::ProviderStore::CreateObject(
	IRand^ rand, Object^ name, Object^ authenticationData, ...array<Object^>^ parameters)
{$
	// создать контейнер
	Using<Container^> container(Container::Create(this, name->ToString(), mode));

	// проверить отсутствие контейнера
	if (container.Get()->KeyType != 0) { AE_CHECK_HRESULT(NTE_EXISTS); }

	// вернуть объект контейнера
	return container.Detach(); 
}

Aladdin::CAPI::SecurityObject^ Aladdin::CAPI::CNG::ProviderStore::OpenObject(
	Object^ name, FileAccess access)
{$
	// открыть контейнер
	return Container::Create(this, name->ToString(), mode);
}

void Aladdin::CAPI::CNG::ProviderStore::DeleteObject(
	Object^ name, array<CAPI::Authentication^>^ authentications)
{$
	// открыть контейнер
	Using<SecurityObject^> container(OpenObject(name, FileAccess::ReadWrite)); 

	// указать тип аутентификации
	container.Get()->Authentications = authentications; 

	// удалить ключи
	((Container^)container.Get())->DeleteKeys();

	// вызвать базовую функцию
	ContainerStore::DeleteObject(name, authentications); 
}

Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::CNG::ProviderStore::GetCertificate(NKeyHandle^ hPrivateKey, 
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	// получить сертификат открытого ключа
	array<BYTE>^ encoded = hPrivateKey->GetSafeParam(NCRYPT_CERTIFICATE_PROPERTY, 0); 

	// вернуть сертификат открытого ключа
	return (encoded != nullptr) ? gcnew Certificate(encoded) : nullptr; 
}

void Aladdin::CAPI::CNG::ProviderStore::SetCertificateChain(
	NKeyHandle^ hPrivateKey, array<Certificate^>^ certificateChain)
{$
	// получить закодированное представление сертификата
	array<BYTE>^ encoded = certificateChain[0]->Encoded; 

	// установить сертификат
	hPrivateKey->SetParam(NCRYPT_CERTIFICATE_PROPERTY, encoded, 0); 
}

///////////////////////////////////////////////////////////////////////////
// Хранилище контейнеров в реестре
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::RegistryStore::RegistryStore(NProvider^ provider, 
	
	// сохранить переданные параметры
	CAPI::Scope scope, DWORD mode) : ProviderStore(provider, scope, 
		
	// указать имя хранилища
	(scope == CAPI::Scope::System) ? "HKLM" : "HKCU", 

	// указать режим открытия
	(scope == CAPI::Scope::System) ? (mode | NCRYPT_MACHINE_KEY_FLAG) : mode) {}

array<String^>^ Aladdin::CAPI::CNG::RegistryStore::EnumerateObjects()
{$
	// для контейнеров локального компьютера
	if (Scope == CAPI::Scope::System)
	{
		// перечислить ключи
		return Provider->Handle->EnumerateKeys(
			nullptr, NCRYPT_SILENT_FLAG | NCRYPT_MACHINE_KEY_FLAG
		); 
	}
	// для контейнеров пользователя
	if (Scope == CAPI::Scope::User)
	{
		// перечислить ключи
		return Provider->Handle->EnumerateKeys(
			nullptr, NCRYPT_SILENT_FLAG
		); 
	}
	// вернуть имена ключей
	return gcnew array<String^>(0); 
}

///////////////////////////////////////////////////////////////////////////
// Смарт-карта как устройство хранения
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::SCardStore::SCardStore(SecurityStore^ store, String^ name, DWORD mode)  

	// сохранить требуемые параметры            
    : ProviderStore(store, name, mode) 
{
	// указать имя смарт-карты
	name = String::Format("\\\\.\\{0}\\", name); 

	// получить описатель ключевой пары
	hCard = Provider->Handle->OpenKey(name, 0, mode | NCRYPT_SILENT_FLAG); 

	// проверить наличие смарт-карты
	if (hCard == nullptr) throw gcnew Win32Exception(NTE_NOT_FOUND); 
}

String^ Aladdin::CAPI::CNG::SCardStore::GetUniqueID()
{$
    // получить подсистему смарт-карт
    PCSC::Windows::Provider^ provider = PCSC::Windows::Provider::Instance; 

	// указать область видимости
	PCSC::ReaderScope readerScope = (Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// получить уникальный идентификатор смарт-карты
	return provider->GetCardUniqueID(readerScope, Name->ToString()); 
}

array<String^>^ Aladdin::CAPI::CNG::SCardStore::EnumerateObjects()
{$
	// определить имя считывателя
	String^ reader = String::Format("\\\\.\\{0}\\", Name);

	// перечислить ключи
	return Provider->Handle->EnumerateKeys(reader, NCRYPT_SILENT_FLAG); 
}

///////////////////////////////////////////////////////////////////////////
// Смарт-карты как устройство хранения
///////////////////////////////////////////////////////////////////////////
array<String^>^ Aladdin::CAPI::CNG::SCardStores::EnumerateObjects()
{$
	// создать список имен считывателей
	List<String^>^ names = gcnew List<String^>(); 

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
		// при наличии смарт-карты добаить имя считывателя
		if (readers[i]->GetState() != PCSC::ReaderState::Card) continue; 
				
		// открыть хранилище
		Using<SecurityObject^> store(OpenObject(readers[i]->Name, FileAccess::Read)); 

		// добавить имя в список
		names->Add(readers[i]->Name);
	}
	// вернуть список имен
	catch (Exception^) {} return names->ToArray(); 
}
